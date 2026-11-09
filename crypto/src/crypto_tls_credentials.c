#include "crypto_tls_credentials.h"
#include "crypto_internal.h"
#include <gmssl/base64.h>
#include <gmssl/aes.h>
#include <gmssl/pbkdf2.h>
#include <gmssl/mem.h>
#include <gmssl/pkcs8.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/x509.h>
#include <gmssl/x509_ext.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

struct crypto_tls_credential_object {
  atomic_size_t references;
  size_t allocation_size;
  bool tlcp;
  crypto_tls_credentials material;
  unsigned char bytes[];
};

static int validate_data(const crypto_tls_data *data, size_t maximum) {
  if (!data || !data->data || !data->size ||
      (data->encoding != CRYPTO_TLS_ENCODING_DER && data->encoding != CRYPTO_TLS_ENCODING_PEM))
    return CRYPTO_TLS_STREAM_EINVAL;
  return data->size > maximum ? CRYPTO_TLS_STREAM_ERANGE : CRYPTO_TLS_STREAM_OK;
}

static int validate_password(const crypto_tls_password *password) {
  if (!password->data && password->size) return CRYPTO_TLS_STREAM_EINVAL;
  return password->size > CRYPTO_TLS_PASSWORD_MAX_BYTES ? CRYPTO_TLS_STREAM_ERANGE : CRYPTO_TLS_STREAM_OK;
}

int crypto_tls_memory_validate(const crypto_tls_data *ca,
    const crypto_tls_credentials *credentials, bool tlcp_server) {
  int status;
  if (ca && (status = validate_data(ca, CRYPTO_TLS_TRUST_INPUT_MAX_BYTES)) != 0) return status;
  if (!credentials) return CRYPTO_TLS_STREAM_OK;
  if (credentials->size != sizeof(*credentials)) return CRYPTO_TLS_STREAM_EINVAL;
  if (credentials->object) {
    if (credentials->certificate_chain.data || credentials->certificate_chain.size || credentials->certificate_chain.encoding ||
        credentials->private_key.data || credentials->private_key.size || credentials->private_key.encoding ||
        credentials->encryption_key.data || credentials->encryption_key.size || credentials->encryption_key.encoding ||
        credentials->private_key_password.data || credentials->private_key_password.size ||
        credentials->encryption_key_password.data || credentials->encryption_key_password.size)
      return CRYPTO_TLS_STREAM_EINVAL;
    return credentials->object->tlcp == tlcp_server ? CRYPTO_TLS_STREAM_OK : CRYPTO_TLS_STREAM_ENOTSUP;
  }
  if ((status = validate_password(&credentials->private_key_password)) != 0 ||
      (status = validate_password(&credentials->encryption_key_password)) != 0) return status;
  if ((status = validate_data(&credentials->certificate_chain, CRYPTO_TLS_CREDENTIAL_INPUT_MAX_BYTES)) != 0 ||
      (status = validate_data(&credentials->private_key, CRYPTO_TLS_CREDENTIAL_INPUT_MAX_BYTES)) != 0)
    return status;
  if (tlcp_server) return validate_data(&credentials->encryption_key, CRYPTO_TLS_CREDENTIAL_INPUT_MAX_BYTES);
  if (credentials->encryption_key.data || credentials->encryption_key.size || credentials->encryption_key.encoding ||
      credentials->encryption_key_password.data || credentials->encryption_key_password.size)
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

/* Shared finite PBES2 policy for PKCS#8 and PKCS#12 encrypted safe contents.
 * The caller retains the authenticated input; all output is erased on error. */
static int decrypt_pbes2(const unsigned char *salt, size_t salt_size, int iterations,
    int key_size, int prf, int cipher, const unsigned char *iv, size_t iv_size,
    const unsigned char *ciphertext, size_t ciphertext_size,
    const crypto_tls_password *password, unsigned char *out, size_t capacity,
    size_t *out_size, uint32_t *work_budget) {
  unsigned char derived[AES256_KEY_SIZE] = {0};
  AES_KEY aes_key = {0};
  SM4_KEY cipher_key = {0};
  int status = CRYPTO_TLS_STREAM_EIO;
  *out_size = 0u;
  const bool sm4 = prf == OID_hmac_sm3 && cipher == OID_sm4_cbc;
  const DIGEST *aes_prf = NULL;
  switch (prf) {
  case OID_hmac_sha224: aes_prf = DIGEST_sha224(); break;
  case OID_hmac_sha256: aes_prf = DIGEST_sha256(); break;
  case OID_hmac_sha384: aes_prf = DIGEST_sha384(); break;
  case OID_hmac_sha512: aes_prf = DIGEST_sha512(); break;
  case OID_hmac_sha512_224: aes_prf = DIGEST_sha512_224(); break;
  case OID_hmac_sha512_256: aes_prf = DIGEST_sha512_256(); break;
  }
  const bool aes = aes_prf &&
      (cipher == OID_aes128_cbc || cipher == OID_aes192_cbc || cipher == OID_aes256_cbc);
  const size_t derived_size = cipher == OID_aes192_cbc ? AES192_KEY_SIZE :
      cipher == OID_aes256_cbc ? AES256_KEY_SIZE : SM4_KEY_SIZE;
  if ((!sm4 && !aes) || (key_size != -1 && key_size != (int)derived_size) ||
      iv_size != 16u || salt_size < 8u || salt_size > 64u ||
      iterations < CRYPTO_TLS_PKCS8_MIN_ITERATIONS || iterations > CRYPTO_TLS_PKCS8_MAX_ITERATIONS ||
      !ciphertext_size || ciphertext_size % 16u) goto end;
  /* The provider writes at most the ciphertext length, including padding. */
  if (ciphertext_size > capacity) { status = CRYPTO_TLS_STREAM_ERANGE; goto end; }
  if (work_budget) {
    if ((uint32_t)iterations > *work_budget) { status = CRYPTO_TLS_STREAM_ERANGE; goto end; }
    *work_budget -= (uint32_t)iterations;
  }
  if (aes) {
    if (pbkdf2_hmac_genkey(aes_prf, password->data, password->size, salt, salt_size,
        (size_t)iterations, derived_size, derived) != 1 ||
        aes_set_decrypt_key(&aes_key, derived, derived_size) != 1 ||
        aes_cbc_padding_decrypt(&aes_key, iv, ciphertext, ciphertext_size, out, out_size) != 1) goto end;
  } else {
    if (sm3_pbkdf2(password->data, password->size, salt, salt_size, (size_t)iterations,
        derived_size, derived) != 1) goto end;
    sm4_set_decrypt_key(&cipher_key, derived);
    if (sm4_cbc_padding_decrypt(&cipher_key, iv, ciphertext, ciphertext_size, out, out_size) != 1) goto end;
  }
  status = CRYPTO_TLS_STREAM_OK;
end:
  gmssl_secure_clear(&aes_key, sizeof(aes_key));
  gmssl_secure_clear(&cipher_key, sizeof(cipher_key));
  gmssl_secure_clear(derived, sizeof(derived));
  if (status != 0) { gmssl_secure_clear(out, capacity); *out_size = 0u; }
  return status;
}

int crypto_tls_pbes2_decrypt(const unsigned char *algorithm, size_t algorithm_size,
    const unsigned char *ciphertext, size_t ciphertext_size,
    const crypto_tls_password *password, unsigned char *out, size_t capacity,
    size_t *out_size, uint32_t *work_budget) {
  const unsigned char *salt, *iv;
  size_t salt_size, iv_size;
  int iterations, key_size, prf, cipher;
  *out_size = 0u;
  if (pbes2_algor_from_der(&salt, &salt_size, &iterations, &key_size, &prf,
      &cipher, &iv, &iv_size, &algorithm, &algorithm_size) != 1 || algorithm_size)
    { gmssl_secure_clear(out, capacity); return CRYPTO_TLS_STREAM_EIO; }
  return decrypt_pbes2(salt, salt_size, iterations, key_size, prf, cipher, iv, iv_size,
      ciphertext, ciphertext_size, password, out, capacity, out_size, work_budget);
}

int crypto_tls_memory_decode_key(const crypto_tls_data *input, const crypto_tls_password *password,
    unsigned char *out, size_t capacity, size_t *out_size, uint32_t *work_budget) {
  if (!password->data) return decode(input, "PRIVATE KEY", false, out, capacity, out_size);
  unsigned char envelope[CRYPTO_TLS_CREDENTIAL_INPUT_MAX_BYTES];
  const unsigned char *salt, *iv, *ciphertext, *cursor = envelope;
  size_t remaining = 0u, salt_size, iv_size, ciphertext_size;
  int iterations, key_size, prf, cipher;
  *out_size = 0u;
  int status = decode(input, "ENCRYPTED PRIVATE KEY", false, envelope, sizeof(envelope), &remaining);
  if (status != 0) goto end;
  status = CRYPTO_TLS_STREAM_EIO;
  if (pkcs8_enced_private_key_info_from_der(&salt, &salt_size, &iterations, &key_size,
      &prf, &cipher, &iv, &iv_size, &ciphertext, &ciphertext_size, &cursor, &remaining) != 1 || remaining)
    goto end;
  status = decrypt_pbes2(salt, salt_size, iterations, key_size, prf, cipher, iv, iv_size,
      ciphertext, ciphertext_size, password, out, capacity, out_size, work_budget);
end:
  gmssl_secure_clear(envelope, sizeof(envelope));
  if (status != 0) { gmssl_secure_clear(out, capacity); *out_size = 0u; }
  return status;
}

int crypto_tls_memory_identity(TLS_CTX *tls, const crypto_tls_credentials *credentials) {
  if (credentials->object) {
    const crypto_tls_credentials *m = &credentials->object->material;
    return tls_ctx_add_certificate_and_keys_der(tls,
        m->certificate_chain.data, m->certificate_chain.size, m->private_key.data, m->private_key.size,
        m->encryption_key.data, m->encryption_key.size) == 1 ? CRYPTO_TLS_STREAM_OK : CRYPTO_TLS_STREAM_EIO;
  }
  unsigned char certs[CRYPTO_TLS_CERTIFICATE_CHAIN_DER_MAX_BYTES];
  unsigned char key[CRYPTO_TLS_PRIVATE_KEY_DER_MAX_BYTES] = {0};
  unsigned char enc_key[CRYPTO_TLS_PRIVATE_KEY_DER_MAX_BYTES] = {0};
  size_t certs_size = 0u, key_size = 0u, enc_size = 0u;
  int status = decode(&credentials->certificate_chain, "CERTIFICATE", true, certs, sizeof(certs), &certs_size);
  if (status == 0) status = crypto_tls_memory_decode_key(&credentials->private_key, &credentials->private_key_password, key, sizeof(key), &key_size, NULL);
  if (status == 0 && tls->protocol == TLS_protocol_tlcp) {
    status = crypto_tls_memory_decode_key(&credentials->encryption_key, &credentials->encryption_key_password, enc_key, sizeof(enc_key), &enc_size, NULL);
    if (status == 0 && !tlcp_roles(certs, certs_size)) status = CRYPTO_TLS_STREAM_EIO;
  }
  if (status == 0 && tls_ctx_add_certificate_and_keys_der(tls, certs, certs_size, key, key_size,
      enc_size ? enc_key : NULL, enc_size) != 1) status = CRYPTO_TLS_STREAM_EIO;
  gmssl_secure_clear(key, sizeof(key));
  gmssl_secure_clear(enc_key, sizeof(enc_key));
  return status;
}

int crypto_tls_credential_object_retain(crypto_tls_credential_object *object) {
  if (!object) return CRYPTO_TLS_STREAM_EINVAL;
  size_t n = atomic_load_explicit(&object->references, memory_order_relaxed);
  do {
    if (n == SIZE_MAX) return CRYPTO_TLS_STREAM_ERANGE;
  } while (!atomic_compare_exchange_weak_explicit(&object->references, &n, n + 1u,
      memory_order_relaxed, memory_order_relaxed));
  return CRYPTO_TLS_STREAM_OK;
}

void crypto_tls_credential_object_release(crypto_tls_credential_object *object) {
  if (object && atomic_fetch_sub_explicit(&object->references, 1u, memory_order_acq_rel) == 1u) {
    gmssl_secure_clear(object, object->allocation_size);
    free(object);
  }
}

int crypto_tls_credential_object_create(const crypto_tls_credentials *input,
    crypto_tls_credential_kind kind, crypto_tls_credential_object **out) {
  if (!out) return CRYPTO_TLS_STREAM_EINVAL;
  if (input && (salts_crypto_overlap(out,sizeof(*out),input,sizeof(*input)) ||
      salts_crypto_overlap(out,sizeof(*out),input->certificate_chain.data,input->certificate_chain.size) ||
      salts_crypto_overlap(out,sizeof(*out),input->private_key.data,input->private_key.size) ||
      salts_crypto_overlap(out,sizeof(*out),input->encryption_key.data,input->encryption_key.size) ||
      salts_crypto_overlap(out,sizeof(*out),input->private_key_password.data,input->private_key_password.size) ||
      salts_crypto_overlap(out,sizeof(*out),input->encryption_key_password.data,input->encryption_key_password.size)))
    return CRYPTO_TLS_STREAM_EINVAL;
  *out = NULL;
  if (!input || input->size != sizeof(*input) || input->object ||
      (kind != CRYPTO_TLS_CREDENTIAL_SINGLE && kind != CRYPTO_TLS_CREDENTIAL_TLCP_SERVER))
    return CRYPTO_TLS_STREAM_EINVAL;
  const bool tlcp = kind == CRYPTO_TLS_CREDENTIAL_TLCP_SERVER;
  int status = crypto_tls_memory_validate(NULL, input, tlcp);
  if (status != CRYPTO_TLS_STREAM_OK) return status;
  unsigned char certs[CRYPTO_TLS_CERTIFICATE_CHAIN_DER_MAX_BYTES];
  unsigned char key[CRYPTO_TLS_PRIVATE_KEY_DER_MAX_BYTES] = {0};
  unsigned char enc[CRYPTO_TLS_PRIVATE_KEY_DER_MAX_BYTES] = {0};
  size_t cert_size = 0u, key_size = 0u, enc_size = 0u;
  crypto_tls_credential_object *object = NULL;
  TLS_CTX check = {0};
  status = decode(&input->certificate_chain, "CERTIFICATE", true, certs, sizeof(certs), &cert_size);
  if (status == 0) status = crypto_tls_memory_decode_key(&input->private_key, &input->private_key_password, key, sizeof(key), &key_size, NULL);
  if (status == 0 && tlcp) {
    status = crypto_tls_memory_decode_key(&input->encryption_key, &input->encryption_key_password, enc, sizeof(enc), &enc_size, NULL);
    if (status == 0 && !tlcp_roles(certs, cert_size)) status = CRYPTO_TLS_STREAM_EIO;
  }
  if (status != 0) goto end;
  /* All three terms have independent <=8192-byte bounds. */
  size_t bytes = cert_size + key_size + enc_size;
  if (bytes > SIZE_MAX - sizeof(*object)) { status = CRYPTO_TLS_STREAM_ERANGE; goto end; }
  object = calloc(1u, sizeof(*object) + bytes);
  if (!object) { status = CRYPTO_TLS_STREAM_ENOMEM; goto end; }
  atomic_init(&object->references, 1u);
  object->allocation_size = sizeof(*object) + bytes;
  object->tlcp = tlcp;
  unsigned char *cursor = object->bytes;
  memcpy(cursor, certs, cert_size);
  object->material = (crypto_tls_credentials){.size = sizeof(crypto_tls_credentials),
      .certificate_chain = {cursor, cert_size, CRYPTO_TLS_ENCODING_DER}};
  cursor += cert_size;
  memcpy(cursor, key, key_size);
  object->material.private_key = (crypto_tls_data){cursor, key_size, CRYPTO_TLS_ENCODING_DER};
  if (tlcp) {
    cursor += key_size; memcpy(cursor, enc, enc_size);
    object->material.encryption_key = (crypto_tls_data){cursor, enc_size, CRYPTO_TLS_ENCODING_DER};
  }
  if (tls_ctx_init(&check, tlcp ? TLS_protocol_tlcp : TLS_protocol_tls13, TLS_server_mode) != 1) {
    status = CRYPTO_TLS_STREAM_EIO; goto end;
  }
  const crypto_tls_credentials view = {.size = sizeof(view), .object = object};
  status = crypto_tls_memory_identity(&check, &view);
  if (status == 0) { *out = object; object = NULL; }
end:
  tls_ctx_cleanup(&check);
  crypto_tls_credential_object_release(object);
  gmssl_secure_clear(key, sizeof(key));
  gmssl_secure_clear(enc, sizeof(enc));
  return status;
}
