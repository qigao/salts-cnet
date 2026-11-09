#ifndef CRYPTO_INTERNAL_H_INCLUDED
#define CRYPTO_INTERNAL_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

/* Range checks avoid forming an out-of-bounds pointer or overflowing an
 * end address. They do not validate the caller's allocation itself. */
static inline int salts_crypto_overlap(const void *a, size_t an,
                                       const void *b, size_t bn) {
  const uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
  if (an == 0u || bn == 0u) return 0;
  return x <= y ? y - x < an : x - y < bn;
}

/* Single Crypto owner; OS CSPRNG has no platform/CFlow dependency. */
int salts_crypto_random_bytes(void *buffer, size_t size);

static inline void salts_crypto_secure_zero(void *buffer, size_t size) {
  volatile unsigned char *p = (volatile unsigned char *)buffer;
  while (size-- != 0u) {
    *p++ = 0u;
  }
}

#endif /* CRYPTO_INTERNAL_H_INCLUDED */
