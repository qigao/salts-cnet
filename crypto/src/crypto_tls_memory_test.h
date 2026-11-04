/* Private formal-test diagnostics; never installed. Source-level operations in
 * crypto_tls_stream.c only, on the calling thread. Not process heap/RSS,
 * GmSSL/NativeIO accounting, memory-bus traffic or a replacement allocator. */
#ifndef CRYPTO_TLS_MEMORY_TEST_H
#define CRYPTO_TLS_MEMORY_TEST_H
#include <stdbool.h>
#include <stdint.h>

typedef enum crypto_tls_test_copy_kind {
  CRYPTO_TLS_TEST_COPY_METADATA,
  CRYPTO_TLS_TEST_COPY_CIPHER_INPUT,
  CRYPTO_TLS_TEST_COPY_PROVIDER_RECEIVE,
  CRYPTO_TLS_TEST_COPY_PROVIDER_SEND,
  CRYPTO_TLS_TEST_COPY_CIPHER_OUTPUT,
  CRYPTO_TLS_TEST_COPY_RECORD_HEADER,
  CRYPTO_TLS_TEST_COPY_PLAINTEXT,
  CRYPTO_TLS_TEST_COPY_PENDING_PLAINTEXT,
  CRYPTO_TLS_TEST_COPY_COUNT
} crypto_tls_test_copy_kind;

typedef struct crypto_tls_test_memory_stats {
  uint64_t allocation_calls, requested_bytes, successful_bytes, failures, releases;
  uint64_t copy_calls[CRYPTO_TLS_TEST_COPY_COUNT];
  uint64_t copied_bytes[CRYPTO_TLS_TEST_COPY_COUNT];
  bool overflow;
} crypto_tls_test_memory_stats;

/* Snapshot only: no reset, explicit allocator call, TLS state access or progress. Counters
 * saturate and mark overflow rather than silently wrapping. Exclusive to the
 * current thread, including creation/destruction performed on that thread.
 * realloc success bytes are the whole request, not net growth/live capacity.
 * Copy calls count explicit source memcpy operations, including ring splits;
 * compiler inlining/vectorization and provider-internal copies are excluded.
 * Compiler-managed thread-local storage is also outside these counters. */
bool crypto_tls_stream_test_memory_snapshot(crypto_tls_test_memory_stats *out);
#endif
