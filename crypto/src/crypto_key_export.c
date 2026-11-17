#include "crypto_key_internal.h"
#include "crypto_internal.h"
#include <stdio.h>
#include <gmssl/asn1.h>
#include <gmssl/base64.h>
#include <limits.h>
#include <string.h>

enum { KEY_DER_CAPACITY = SALTS_CRYPTO_KEY_DER_MAX_SIZE, ENCRYPTED_CAPACITY = KEY_DER_CAPACITY + 256 };
static const uint8_t rsa_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1};
static const uint8_t ec_oid[] = {0x2a,0x86,0x48,0xce,0x3d,2,1};
static const uint8_t pbes2_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,5,13};
static const uint8_t pbkdf2_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,5,12};
static const uint8_t hmac256_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,2,9};
static const uint8_t aes256_oid[] = {0x60,0x86,0x48,1,0x65,3,4,1,42};
static const uint8_t curves[][8] = {
  {0x2a,0x86,0x48,0xce,0x3d,3,1,7}, {0x2b,0x81,4,0,0x22},
  {0x2b,0x81,4,0,0x23}, {0x2b,0x81,4,0,0x0a}
};

static int put(int tag, const void *data, size_t size, uint8_t **out, size_t *written) {
  return asn1_type_to_der(tag, data, size, out, written) == 1;
}

static int encode_key(const salts_crypto_key *key, int secret, uint8_t result[KEY_DER_CAPACITY], size_t *size) {
  uint8_t payload[KEY_DER_CAPACITY], algorithm[32], body[KEY_DER_CAPACITY];
  uint8_t *p = payload, *a = algorithm, *b = body, *out = result;
  size_t pn = 0, an = 0, bn = 0, n = 0;
  int ok = 0;
  if (!key || (secret != 0 && secret != 1) || (secret && !key->has_private))
    return SALTS_CRYPTO_EINVAL;
  if (key->kind == SALTS_CRYPTO_KEY_RSA) {
    uint8_t exponent[8]; uint64_t e = key->value.rsa.e;
    if (secret && !key->crt) return SALTS_CRYPTO_EINVAL;
    for (size_t i = 8; i > 0; --i) { exponent[i-1] = (uint8_t)e; e >>= 8; }
    if ((secret && asn1_int_to_der(0, &p, &pn) != 1) ||
        asn1_integer_to_der(key->value.rsa.n, key->value.rsa.size, &p, &pn) != 1 ||
        asn1_integer_to_der(exponent, sizeof(exponent), &p, &pn) != 1) goto done;
    if (secret) {
      if (asn1_integer_to_der(key->value.rsa.d, key->value.rsa.size, &p, &pn) != 1) goto done;
      for (size_t i = 0; i < 5; ++i)
        if (asn1_integer_to_der(key->crt->data[i], key->crt->size[i], &p, &pn) != 1) goto done;
    }
    if (!put(ASN1_TAG_OBJECT_IDENTIFIER, rsa_oid, sizeof(rsa_oid), &a, &an) ||
        asn1_null_to_der(&a, &an) != 1) goto done;
    /* The PKCS1 payload receives its own sequence inside SPKI/PKCS8. */
    if (!put(ASN1_TAG_SEQUENCE, payload, pn, &b, &bn)) goto done;
  } else if (key->kind == SALTS_CRYPTO_KEY_EC) {
    size_t ci = (size_t)key->curve - 1;
    if (ci >= 4 || !put(ASN1_TAG_OBJECT_IDENTIFIER, ec_oid, sizeof(ec_oid), &a, &an) ||
        !put(ASN1_TAG_OBJECT_IDENTIFIER, curves[ci], ci ? 5 : 8, &a, &an)) goto done;
    if (secret) {
      if (asn1_int_to_der(1, &p, &pn) != 1 ||
          !put(ASN1_TAG_OCTET_STRING, key->value.ec.private_key, key->scalar_size, &p, &pn) ||
          !put(ASN1_TAG_SEQUENCE, payload, pn, &b, &bn)) goto done;
    } else {
      body[0] = 4; memcpy(body + 1, key->value.ec.public_key, 2 * key->scalar_size);
      bn = 1 + 2 * key->scalar_size;
    }
  } else if (key->kind == SALTS_CRYPTO_KEY_ED25519 || key->kind == SALTS_CRYPTO_KEY_ED448) {
    uint8_t oid[3] = {0x2b,0x65, key->kind == SALTS_CRYPTO_KEY_ED25519 ? 0x70 : 0x71};
    if (!put(ASN1_TAG_OBJECT_IDENTIFIER, oid, sizeof(oid), &a, &an)) goto done;
    if (secret) {
      if (!put(ASN1_TAG_OCTET_STRING, key->value.ec.private_key, key->scalar_size, &b, &bn)) goto done;
    } else { memcpy(body, key->value.ec.public_key, key->scalar_size); bn = key->scalar_size; }
  } else goto done;
  p = payload; pn = 0;
  if ((secret && asn1_int_to_der(0, &p, &pn) != 1) ||
      !put(ASN1_TAG_SEQUENCE, algorithm, an, &p, &pn)) goto done;
  if (secret) { if (!put(ASN1_TAG_OCTET_STRING, body, bn, &p, &pn)) goto done; }
  else if (asn1_bit_octets_to_der(body, bn, &p, &pn) != 1) goto done;
  if (!put(ASN1_TAG_SEQUENCE, payload, pn, &out, &n)) goto done;
  *size = n; ok = 1;
done:
  salts_crypto_clear(payload, sizeof(payload)); salts_crypto_clear(body, sizeof(body));
  return ok ? SALTS_CRYPTO_OK : SALTS_CRYPTO_ECRYPTO;
}

static int deliver(const void *data, size_t n, void *output, size_t capacity, size_t *size) {
  if (!size) return SALTS_CRYPTO_EINVAL;
  *size = 0;
  if (!output && !capacity) { *size = n; return SALTS_CRYPTO_OK; }
  if (!output || capacity < n) return SALTS_CRYPTO_EINVAL;
  memcpy(output, data, n); *size = n;
  return SALTS_CRYPTO_OK;
}

static int export_arguments(const salts_crypto_key *key, void *output, size_t capacity, size_t *size) {
  if (!size || salts_crypto_overlap(size, sizeof(*size), output, capacity) ||
      (key && (salts_crypto_overlap(output, capacity, key, sizeof(*key)) ||
      salts_crypto_overlap(size, sizeof(*size), key, sizeof(*key))))) return 0;
  *size = 0;
  return 1;
}

int salts_crypto_key_to_der(const salts_crypto_key *key, int secret,
    uint8_t *output, size_t capacity, size_t *size) {
  uint8_t der[KEY_DER_CAPACITY]; size_t n = 0;
  int ret;
  if (!export_arguments(key, output, capacity, size)) return SALTS_CRYPTO_EINVAL;
  ret = encode_key(key, secret, der, &n);
  if (ret == SALTS_CRYPTO_OK) ret = deliver(der, n, output, capacity, size);
  salts_crypto_clear(der, sizeof(der));
  return ret;
}

static int pem_encode(const uint8_t *der, size_t n, const char *label,
    char *output, size_t capacity, size_t *size) {
  uint8_t encoded[4 * ((ENCRYPTED_CAPACITY + 2) / 3) + 1];
  char pem[16384];
  size_t en = 4 * ((n + 2) / 3), label_size = strlen(label), offset = 0;
  int ret;
  memcpy(pem, "-----BEGIN ", 11); offset = 11;
  memcpy(pem + offset, label, label_size); offset += label_size;
  memcpy(pem + offset, "-----\n", 6); offset += 6;
  if (base64_encode_block(encoded, der, (int)n) != (int)en) {
    salts_crypto_clear(encoded, sizeof(encoded)); salts_crypto_clear(pem, sizeof(pem));
    return SALTS_CRYPTO_ECRYPTO;
  }
  for (size_t i = 0; i < en; i += 64) {
    size_t count = en - i < 64 ? en - i : 64;
    memcpy(pem + offset, encoded + i, count); offset += count; pem[offset++] = '\n';
  }
  memcpy(pem + offset, "-----END ", 9); offset += 9;
  memcpy(pem + offset, label, label_size); offset += label_size;
  memcpy(pem + offset, "-----\n", 6); offset += 6;
  ret = deliver(pem, offset, output, capacity, size);
  salts_crypto_clear(encoded, sizeof(encoded)); salts_crypto_clear(pem, sizeof(pem));
  return ret;
}

int salts_crypto_key_to_pem(const salts_crypto_key *key, int secret,
    char *output, size_t capacity, size_t *size) {
  uint8_t der[KEY_DER_CAPACITY]; size_t n = 0; int ret;
  if (!export_arguments(key, output, capacity, size)) return SALTS_CRYPTO_EINVAL;
  ret = encode_key(key, secret, der, &n);
  if (ret == SALTS_CRYPTO_OK) ret = pem_encode(der, n, secret ? "PRIVATE KEY" : "PUBLIC KEY", output, capacity, size);
  salts_crypto_clear(der, sizeof(der));
  return ret;
}

static int password_arguments(const void *password, size_t size, uint32_t iterations) {
  return (password || !size) && (uint64_t)size <= UINT64_MAX / 8 - 144 &&
    iterations >= SALTS_CRYPTO_KEY_ITERATIONS_MIN && iterations <= INT_MAX;
}

/* The provider's PKCS8 encoder only admits SM3/SM4. Encode this explicit AES
 * profile with its existing DER primitives, without changing provider policy
 * or searching for a different implementation after an error. */
static int encrypted_der(const uint8_t salt[16], int iterations, const uint8_t iv[16],
    const uint8_t *cipher, size_t cn, uint8_t *output, size_t *size) {
  uint8_t prf[32], kdf_params[128], kdf[160], scheme[64], pair[256], alg[300], body[ENCRYPTED_CAPACITY];
  uint8_t *p = prf, *kp = kdf_params, *k = kdf, *s = scheme, *b = pair, *a = alg, *all = body;
  size_t pn = 0, kpn = 0, kn = 0, sn = 0, bn = 0, an = 0, alln = 0;
  return put(ASN1_TAG_OBJECT_IDENTIFIER, hmac256_oid, sizeof(hmac256_oid), &p, &pn) &&
    asn1_null_to_der(&p, &pn) == 1 &&
    put(ASN1_TAG_OCTET_STRING, salt, 16, &kp, &kpn) &&
    asn1_int_to_der(iterations, &kp, &kpn) == 1 && asn1_int_to_der(32, &kp, &kpn) == 1 &&
    put(ASN1_TAG_SEQUENCE, prf, pn, &kp, &kpn) &&
    put(ASN1_TAG_OBJECT_IDENTIFIER, pbkdf2_oid, sizeof(pbkdf2_oid), &k, &kn) &&
    put(ASN1_TAG_SEQUENCE, kdf_params, kpn, &k, &kn) &&
    put(ASN1_TAG_OBJECT_IDENTIFIER, aes256_oid, sizeof(aes256_oid), &s, &sn) &&
    put(ASN1_TAG_OCTET_STRING, iv, 16, &s, &sn) &&
    put(ASN1_TAG_SEQUENCE, kdf, kn, &b, &bn) && put(ASN1_TAG_SEQUENCE, scheme, sn, &b, &bn) &&
    put(ASN1_TAG_OBJECT_IDENTIFIER, pbes2_oid, sizeof(pbes2_oid), &a, &an) &&
    put(ASN1_TAG_SEQUENCE, pair, bn, &a, &an) &&
    put(ASN1_TAG_SEQUENCE, alg, an, &all, &alln) &&
    put(ASN1_TAG_OCTET_STRING, cipher, cn, &all, &alln) &&
    put(ASN1_TAG_SEQUENCE, body, alln, output ? &output : NULL, size);
}

typedef struct { const uint8_t *data; size_t size; } key_der_view;
static int enter(key_der_view *in, int tag, key_der_view *out) {
  return asn1_type_from_der(tag, &out->data, &out->size, &in->data, &in->size) == 1;
}
static int match_oid(key_der_view *in, const uint8_t *oid, size_t n) {
  key_der_view v;
  return enter(in, ASN1_TAG_OBJECT_IDENTIFIER, &v) && v.size == n && !memcmp(v.data, oid, n);
}
static int encrypted_view(const void *der, size_t size, uint32_t ceiling,
    key_der_view *salt, uint32_t *iterations, key_der_view *iv, key_der_view *cipher) {
  key_der_view input = {der, size}, body, alg, pair, kdf, params, prf, scheme, null_value;
  int count, key_size = -1;
  if (!enter(&input, ASN1_TAG_SEQUENCE, &body) || input.size ||
      !enter(&body, ASN1_TAG_SEQUENCE, &alg) || !match_oid(&alg, pbes2_oid, sizeof(pbes2_oid)) ||
      !enter(&alg, ASN1_TAG_SEQUENCE, &pair) || alg.size ||
      !enter(&pair, ASN1_TAG_SEQUENCE, &kdf) || !match_oid(&kdf, pbkdf2_oid, sizeof(pbkdf2_oid)) ||
      !enter(&kdf, ASN1_TAG_SEQUENCE, &params) || kdf.size ||
      !enter(&params, ASN1_TAG_OCTET_STRING, salt) || salt->size < 8 || salt->size > 64 ||
      asn1_int_from_der(&count, &params.data, &params.size) != 1 ||
      count < (int)SALTS_CRYPTO_KEY_ITERATIONS_MIN || (uint32_t)count > ceiling)
    return 0;
  if (params.size && params.data[0] == ASN1_TAG_INTEGER &&
      (asn1_int_from_der(&key_size, &params.data, &params.size) != 1 || key_size != 32)) return 0;
  if (!enter(&params, ASN1_TAG_SEQUENCE, &prf) || params.size ||
      !match_oid(&prf, hmac256_oid, sizeof(hmac256_oid)) ||
      (prf.size && (!enter(&prf, ASN1_TAG_NULL, &null_value) || null_value.size)) || prf.size ||
      !enter(&pair, ASN1_TAG_SEQUENCE, &scheme) || pair.size ||
      !match_oid(&scheme, aes256_oid, sizeof(aes256_oid)) ||
      !enter(&scheme, ASN1_TAG_OCTET_STRING, iv) || scheme.size || iv->size != 16 ||
      !enter(&body, ASN1_TAG_OCTET_STRING, cipher) || body.size ||
      !cipher->size || cipher->size > KEY_DER_CAPACITY + 16 || cipher->size % 16) return 0;
  *iterations = (uint32_t)count;
  return 1;
}

int salts_crypto_key_to_encrypted_der(const salts_crypto_key *key,
    const void *password, size_t password_size, uint32_t iterations,
    uint8_t *output, size_t capacity, size_t *size) {
  uint8_t plain[KEY_DER_CAPACITY + 16], cipher[KEY_DER_CAPACITY + 16] = {0}, der[ENCRYPTED_CAPACITY];
  uint8_t salt[16] = {0}, iv[16] = {0}, derived[32] = {0};
  size_t n = 0, cn = 0, dn = 0;
  int ret;
  if ((size && salts_crypto_overlap(size, sizeof(*size), password, password_size)) ||
      salts_crypto_overlap(output, capacity, password, password_size) ||
      !export_arguments(key, output, capacity, size)) return SALTS_CRYPTO_EINVAL;
  if (!password_arguments(password, password_size, iterations)) return SALTS_CRYPTO_EINVAL;
  ret = encode_key(key, 1, plain, &n);
  if (ret != SALTS_CRYPTO_OK) goto done;
  cn = n + 16 - n % 16;
  if (!encrypted_der(salt, (int)iterations, iv, cipher, cn, NULL, &dn) || dn > sizeof(der)) {
    ret = SALTS_CRYPTO_ECRYPTO; goto done;
  }
  if (!output && !capacity) { *size = dn; goto done; }
  if (!output || capacity < dn) { ret = SALTS_CRYPTO_EINVAL; goto done; }
  ret = salts_crypto_random(salt, sizeof(salt));
  if (ret != SALTS_CRYPTO_OK) goto done;
  ret = salts_crypto_random(iv, sizeof(iv));
  if (ret != SALTS_CRYPTO_OK) goto done;
  ret = salts_crypto_pbkdf2(SALTS_CRYPTO_SHA256, password, password_size, salt, sizeof(salt), iterations, derived, sizeof(derived));
  if (ret != SALTS_CRYPTO_OK) goto done;
  memset(plain + n, (int)(cn - n), cn - n);
  ret = salts_crypto_aes_crypt(SALTS_CRYPTO_AES_CBC, 0, derived, sizeof(derived),
      iv, plain, cn, cipher, sizeof(cipher));
  if (ret != SALTS_CRYPTO_OK) goto done;
  dn = 0;
  if (!encrypted_der(salt, (int)iterations, iv, cipher, cn, der, &dn)) {
    ret = SALTS_CRYPTO_ECRYPTO; goto done;
  }
  ret = deliver(der, dn, output, capacity, size);
done:
  salts_crypto_clear(plain, sizeof(plain)); salts_crypto_clear(cipher, sizeof(cipher));
  salts_crypto_clear(der, sizeof(der)); salts_crypto_clear(derived, sizeof(derived));
  return ret;
}

int salts_crypto_key_to_encrypted_pem(const salts_crypto_key *key,
    const void *password, size_t password_size, uint32_t iterations,
    char *output, size_t capacity, size_t *size) {
  uint8_t der[ENCRYPTED_CAPACITY] = {0}; size_t n = 0, required = 0; int ret;
  if ((size && salts_crypto_overlap(size, sizeof(*size), password, password_size)) ||
      salts_crypto_overlap(output, capacity, password, password_size) ||
      !export_arguments(key, output, capacity, size)) return SALTS_CRYPTO_EINVAL;
  ret = salts_crypto_key_to_encrypted_der(key, password, password_size, iterations, NULL, 0, &n);
  if (ret != SALTS_CRYPTO_OK) return ret;
  ret = pem_encode(der, n, "ENCRYPTED PRIVATE KEY", NULL, 0, &required);
  if (ret != SALTS_CRYPTO_OK) return ret;
  if (!output && !capacity) { *size = required; return SALTS_CRYPTO_OK; }
  if (!output || capacity < required) return SALTS_CRYPTO_EINVAL;
  ret = salts_crypto_key_to_encrypted_der(key, password, password_size, iterations, der, sizeof(der), &n);
  if (ret == SALTS_CRYPTO_OK) ret = pem_encode(der, n, "ENCRYPTED PRIVATE KEY", output, capacity, size);
  salts_crypto_clear(der, sizeof(der));
  return ret;
}

int salts_crypto_key_from_encrypted_der(const void *der, size_t size,
    const void *password, size_t password_size, uint32_t max_iterations,
    salts_crypto_key **output) {
  key_der_view salt, iv, cipher;
  size_t pn = 0;
  uint32_t iterations;
  int ret = SALTS_CRYPTO_EINVAL;
  uint8_t plain[KEY_DER_CAPACITY + 16], derived[32];
  if (!output) return SALTS_CRYPTO_EINVAL;
  *output = NULL;
  if (!der || !size || size > ENCRYPTED_CAPACITY ||
      !password_arguments(password, password_size, max_iterations)) return ret;
  if (!encrypted_view(der, size, max_iterations, &salt, &iterations, &iv, &cipher)) return ret;
  ret = salts_crypto_pbkdf2(SALTS_CRYPTO_SHA256, password, password_size, salt.data, salt.size,
      iterations, derived, sizeof(derived));
  if (ret != SALTS_CRYPTO_OK) goto done;
  ret = salts_crypto_aes_crypt(SALTS_CRYPTO_AES_CBC, 1, derived, sizeof(derived),
      iv.data, cipher.data, cipher.size, plain, sizeof(plain));
  if (ret != SALTS_CRYPTO_OK) goto done;
  {
    unsigned pad = plain[cipher.size - 1], bad = (pad - 1u) > 15u;
    /* Inspect the complete final block without a data-dependent early return. */
    for (unsigned i = 1; i <= 16; ++i)
      bad |= (plain[cipher.size - i] ^ pad) & (0u - (unsigned)(i <= pad));
    if (bad) { ret = SALTS_CRYPTO_EVERIFY; goto done; }
    pn = cipher.size - pad;
  }
  ret = salts_crypto_key_from_der(plain, pn, 1, output);
  if (ret != SALTS_CRYPTO_OK && ret != SALTS_CRYPTO_ENOMEM) ret = SALTS_CRYPTO_EVERIFY;
done:
  salts_crypto_clear(plain, sizeof(plain)); salts_crypto_clear(derived, sizeof(derived));
  return ret;
}

int salts_crypto_key_from_encrypted_pem(const void *pem, size_t size,
    const void *password, size_t password_size, uint32_t max_iterations,
    salts_crypto_key **output) {
  static const char begin[] = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
  static const char end[] = "-----END ENCRYPTED PRIVATE KEY-----";
  uint8_t der[ENCRYPTED_CAPACITY + 80];
  const uint8_t *data = pem; size_t offset = 0, finish;
  BASE64_CTX native; int n = 0, tail = 0, ret = SALTS_CRYPTO_EINVAL;
  if (!output) return ret;
  *output = NULL;
  if (!pem || size > 16384 || !password_arguments(password, password_size, max_iterations)) return ret;
  while (offset < size && (data[offset] == ' ' || data[offset] == '\r' || data[offset] == '\n' || data[offset] == '\t')) ++offset;
  if (size - offset < sizeof(begin) - 1 || memcmp(data + offset, begin, sizeof(begin) - 1)) return ret;
  offset += sizeof(begin) - 1;
  for (finish = offset; finish < size; ++finish)
    if (size - finish >= sizeof(end) - 1 && !memcmp(data + finish, end, sizeof(end) - 1)) break;
  if (finish == size) return ret;
  for (size_t i = finish + sizeof(end) - 1; i < size; ++i)
    if (data[i] != ' ' && data[i] != '\r' && data[i] != '\n' && data[i] != '\t') return ret;
  base64_decode_init(&native);
  if (base64_decode_update_ex(&native, data + offset, (int)(finish - offset), der, &n, sizeof(der)) >= 0 && n >= 0 &&
      base64_decode_finish_ex(&native, der + n, &tail, sizeof(der) - (size_t)n) == 1 && tail >= 0)
    ret = salts_crypto_key_from_encrypted_der(der, (size_t)n + (size_t)tail,
        password, password_size, max_iterations, output);
  salts_crypto_clear(der, sizeof(der)); salts_crypto_clear(&native, sizeof(native));
  return ret;
}
