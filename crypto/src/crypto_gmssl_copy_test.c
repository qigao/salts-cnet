/* Compiled into the existing gmssl archive only by the diagnostic triplet. */
#include "crypto_gmssl_copy_test.h"
#include <string.h>

#if !defined(__linux__) || (!defined(__GNUC__) && !defined(__clang__))
#error GmSSL copy profiling requires Linux GCC or Clang
#endif

static _Thread_local crypto_gmssl_copy_stats salts_gmssl_copies;
static void salts_gmssl_copy_add(uint64_t *value, uint64_t amount) {
  if (amount > UINT64_MAX - *value) {
    *value = UINT64_MAX;
    salts_gmssl_copies.overflow = true;
  } else *value += amount;
}
__attribute__((visibility("hidden")))
void salts_gmssl_copy_record(const char *function, unsigned operation, size_t bytes) {
  unsigned bucket = CRYPTO_GMSSL_COPY_OTHER;
  if (strcmp(function, "tls13_gcm_encrypt") == 0) bucket = CRYPTO_GMSSL_COPY_ENCRYPT;
  else if (strcmp(function, "tls13_gcm_decrypt") == 0) bucket = CRYPTO_GMSSL_COPY_DECRYPT;
  salts_gmssl_copy_add(&salts_gmssl_copies.calls[bucket][operation], 1u);
  salts_gmssl_copy_add(&salts_gmssl_copies.bytes[bucket][operation], (uint64_t)bytes);
}
__attribute__((visibility("hidden")))
bool salts_gmssl_copy_snapshot(crypto_gmssl_copy_stats *out) {
  if (out == NULL) return false;
  *out = salts_gmssl_copies;
  return true;
}
