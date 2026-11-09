/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CRYPTO_TLS_SIGNATURE_H
#define CRYPTO_TLS_SIGNATURE_H

/* Qualified SignatureScheme identifiers; other provider schemes are rejected. */
typedef enum crypto_tls_signature_scheme {
  CRYPTO_TLS_SIGNATURE_RSA_PKCS1_SHA256 = 0x0401,
  CRYPTO_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256 = 0x0403,
  CRYPTO_TLS_SIGNATURE_ECDSA_SECP384R1_SHA384 = 0x0503,
  CRYPTO_TLS_SIGNATURE_SM2_SM3 = 0x0708,
  CRYPTO_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256 = 0x0804
} crypto_tls_signature_scheme;

enum { CRYPTO_TLS_SIGNATURE_MAX_COUNT = 4 };

#endif
