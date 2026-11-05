/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CRYPTO_TLS_CIPHER_H
#define CRYPTO_TLS_CIPHER_H

/* Qualified wire identifiers, not an unrestricted provider pass-through. */
typedef enum crypto_tls_cipher_suite {
  CRYPTO_TLS_CIPHER_AES_128_GCM_SHA256 = 0x1301,
  CRYPTO_TLS_CIPHER_ECDHE_RSA_AES_128_GCM_SHA256 = 0xc02f,
  CRYPTO_TLS_CIPHER_ECDHE_ECDSA_AES_128_GCM_SHA256 = 0xc02b,
  CRYPTO_TLS_CIPHER_SM4_GCM_SM3 = 0x00c6,
  CRYPTO_TLS_CIPHER_TLCP_ECC_SM4_GCM_SM3 = 0xe053
} crypto_tls_cipher_suite;

enum { CRYPTO_TLS_CIPHER_SUITE_MAX_COUNT = 3 };

#endif
