#include "crypto_dtls_srtp.h"
#include "crypto_dtls_wire.h"
#include "crypto_internal.h"
#include <gmssl/mem.h>
#include <gmssl/oid.h>
#include <gmssl/sha2.h>
#include <gmssl/x509.h>
#include <time.h>

static const uint16_t preferred_profiles[] = {
    CRYPTO_DTLS_SRTP_AES128_CM_SHA1_80, CRYPTO_DTLS_SRTP_AES128_CM_SHA1_32,
    CRYPTO_DTLS_SRTP_AEAD_AES_128_GCM, CRYPTO_DTLS_SRTP_AEAD_AES_256_GCM
};

size_t dtls_srtp_extension(uint8_t *out, unsigned profiles) {
  size_t profile_bytes = 0;
  for (size_t i = 0; i < sizeof(preferred_profiles) / sizeof(*preferred_profiles); ++i) {
    const uint16_t profile = preferred_profiles[i];
    if (!(profiles & (1u << profile)))
      continue;
    out[6 + profile_bytes++] = 0;
    out[6 + profile_bytes++] = (uint8_t)profile;
  }
  out[0] = 0;
  out[1] = CRYPTO_DTLS_EXT_USE_SRTP;
  out[2] = 0;
  out[3] = (uint8_t)(profile_bytes + 3);
  out[4] = 0;
  out[5] = (uint8_t)profile_bytes;
  out[6 + profile_bytes] = 0;
  return profile_bytes + 7;
}

uint16_t dtls_srtp_select(const uint8_t *data, size_t size,
                                unsigned profiles, bool server_hello) {
  if (size < 5)
    return 0;
  const size_t list_size = (size_t)data[0] * 256 + data[1];
  if (!list_size || list_size % 2 || list_size > size - 3 ||
      data[2 + list_size] != size - 3 - list_size ||
      (server_hello && (list_size != 2 || size != 5)))
    return 0;
  unsigned matched = 0;
  for (size_t offset = 2; offset < list_size + 2; offset += 2) {
    const unsigned id = (unsigned)data[offset] * 256 + data[offset + 1];
    if (id <= CRYPTO_DTLS_SRTP_AEAD_AES_256_GCM && (profiles & (1u << id)))
      matched |= 1u << id;
  }
  for (size_t i = 0; i < sizeof(preferred_profiles) / sizeof(*preferred_profiles); ++i) {
    if (matched & (1u << preferred_profiles[i]))
      return preferred_profiles[i];
  }
  return 0;
}

bool dtls_srtp_fingerprint(const uint8_t *chain, size_t chain_size,
                                 const uint8_t expected[32]) {
  crypto_tls_stream_peer_certificate_chain view;
  if (crypto_dtls_chain_views(chain, chain_size, &view) != 0 || !view.count)
    return false;
  uint8_t digest[32];
  SHA256_CTX hash;
  sha256_init(&hash);
  sha256_update(&hash, view.certificates[0].data, view.certificates[0].size);
  sha256_finish(&hash, digest);
  return gmssl_secure_memcmp(digest, expected, sizeof(digest)) == 0;
}

int crypto_dtls_srtp_identity_create(crypto_tls_credential_object **out) {
  if (!out)
    return SALTS_CRYPTO_EINVAL;
  *out = NULL;
  const time_t start = time(NULL);
  const time_t year = 365 * 24 * 60 * 60;
  time_t end;
  /* Check addition at the platform's time_t width before using the result. */
  if (start < 0 || (sizeof(time_t) <= 4 && start > INT32_MAX - year) ||
      (sizeof(time_t) > 4 && start > INT64_MAX - year))
    return SALTS_CRYPTO_ESTATE;
  end = start + year;
  uint8_t serial[16], name[128];
  size_t name_size = 0;
  if (salts_crypto_random_bytes(serial, sizeof(serial)) != 0)
    return SALTS_CRYPTO_ERANDOM;
  serial[0] = (uint8_t)((serial[0] & 0x7f) | 1);
  if (x509_name_set(name, &name_size, sizeof(name), NULL, NULL, NULL, NULL,
                    NULL, "DTLS-SRTP") != 1)
    return SALTS_CRYPTO_ECRYPTO;

  uint8_t cert[CRYPTO_DTLS_WIRE_CHAIN_BYTES], key_der[CRYPTO_TLS_PRIVATE_KEY_DER_MAX_BYTES];
  uint8_t *cert_pos = cert, *key_pos = key_der;
  size_t cert_size = 0, key_size = 0;
  X509_KEY key = {0};
  const int curve = OID_secp256r1;
  int status = SALTS_CRYPTO_ECRYPTO;
  if (x509_key_generate(&key, OID_ec_public_key, &curve, sizeof(curve)) != 1 ||
      x509_cert_sign_to_der(X509_version_v3, serial, sizeof(serial), OID_ecdsa_with_sha256,
        name, name_size, start, end, name, name_size, &key, NULL, 0, NULL, 0,
        NULL, 0, &key, NULL, 0, &cert_pos, &cert_size) != 1 ||
      x509_private_key_info_to_der(&key, &key_pos, &key_size) != 1)
    goto done;
  const crypto_tls_credentials input = {
      .size = sizeof(input),
      .certificate_chain = {cert, cert_size, CRYPTO_TLS_ENCODING_DER},
      .private_key = {key_der, key_size, CRYPTO_TLS_ENCODING_DER}};
  status = crypto_tls_credential_object_create(&input, CRYPTO_TLS_CREDENTIAL_SINGLE, out);
done:
  x509_key_cleanup(&key);
  salts_crypto_secure_zero(key_der, sizeof(key_der));
  return status;
}
