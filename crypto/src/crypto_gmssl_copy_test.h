/* Private diagnostic contract; not installed. See the measurement protocol. */
#ifndef CRYPTO_GMSSL_COPY_TEST_H
#define CRYPTO_GMSSL_COPY_TEST_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { CRYPTO_GMSSL_COPY_ENCRYPT, CRYPTO_GMSSL_COPY_DECRYPT,
       CRYPTO_GMSSL_COPY_OTHER, CRYPTO_GMSSL_COPY_BUCKETS };
enum { CRYPTO_GMSSL_MEMCPY, CRYPTO_GMSSL_MEMMOVE, CRYPTO_GMSSL_COPY_OPERATIONS };
typedef struct crypto_gmssl_copy_stats {
  uint64_t calls[CRYPTO_GMSSL_COPY_BUCKETS][CRYPTO_GMSSL_COPY_OPERATIONS];
  uint64_t bytes[CRYPTO_GMSSL_COPY_BUCKETS][CRYPTO_GMSSL_COPY_OPERATIONS];
  bool overflow;
} crypto_gmssl_copy_stats;

void salts_gmssl_copy_record(const char *function, unsigned operation, size_t bytes);
bool salts_gmssl_copy_snapshot(crypto_gmssl_copy_stats *out);

#if defined(SALTS_GMSSL_COPY_INJECT)
#include <string.h>
static inline void *salts_gmssl_profile_memcpy(void *to, const void *from, size_t bytes,
                                             const char *function) {
  void *result = __builtin_memcpy(to, from, bytes);
  salts_gmssl_copy_record(function, CRYPTO_GMSSL_MEMCPY, bytes);
  return result;
}
static inline void *salts_gmssl_profile_memmove(void *to, const void *from, size_t bytes,
                                              const char *function) {
  void *result = __builtin_memmove(to, from, bytes);
  salts_gmssl_copy_record(function, CRYPTO_GMSSL_MEMMOVE, bytes);
  return result;
}
#define memcpy(to, from, bytes) salts_gmssl_profile_memcpy((to), (from), (bytes), __func__)
#define memmove(to, from, bytes) salts_gmssl_profile_memmove((to), (from), (bytes), __func__)
#endif
#endif
