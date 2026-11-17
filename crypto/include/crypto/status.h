#ifndef CRYPTO_STATUS_H_INCLUDED
#define CRYPTO_STATUS_H_INCLUDED

/* Preserve the algorithm result ABI while relocating the public headers. */
typedef enum salts_crypto_status {
  SALTS_CRYPTO_OK = 0,
  SALTS_CRYPTO_EINVAL = -1,
  SALTS_CRYPTO_EVERIFY = -2,
  SALTS_CRYPTO_ERANDOM = -3,
  SALTS_CRYPTO_ECRYPTO = -4,
  SALTS_CRYPTO_ESTATE = -5,
  SALTS_CRYPTO_ENOMEM = -6
} salts_crypto_status;

#endif /* CRYPTO_STATUS_H_INCLUDED */
